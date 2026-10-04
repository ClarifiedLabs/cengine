// A bounded stdlib syscall probe. PID 1 owns descriptors across serial exec requests.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"
	"time"
)

type operation struct {
	Op   string `json:"op"`
	Path string `json:"path"`
	To   string `json:"to"`
	FD   string `json:"fd"`
	Data string `json:"data"`
	Size int64  `json:"size"`
	Mode uint32 `json:"mode"`
}

type server struct {
	root  string
	files map[string]*os.File
}

func errno(err error) int {
	if err == nil {
		return 0
	}
	var value syscall.Errno
	if errors.As(err, &value) {
		return int(value)
	}
	return -1 // Non-syscall failures remain visible, never converted to success.
}

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func (s *server) apply(op operation) error {
	for _, name := range []string{op.Path, op.To, op.FD} {
		if name != "" && !namePattern.MatchString(name) {
			return syscall.EINVAL
		}
	}
	path := filepath.Join(s.root, op.Path)
	destination := filepath.Join(s.root, op.To)
	if op.Size < 0 || op.Size > 4096 || len(op.Data) > 4096 || op.Mode > 0777 {
		return syscall.EINVAL
	}
	switch op.Op {
	case "snapshot":
		return nil
	case "create":
		if op.Path == "" {
			return syscall.EINVAL
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err = f.WriteString(op.Data); err != nil {
			return err
		}
		return f.Sync()
	case "open":
		if op.Path == "" || op.FD == "" {
			return syscall.EINVAL
		}
		if s.files[op.FD] != nil {
			return syscall.EEXIST
		}
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err == nil {
			s.files[op.FD] = f
		}
		return err
	case "close", "write_fd":
		f := s.files[op.FD]
		if f == nil {
			return syscall.EBADF
		}
		if op.Op == "close" {
			delete(s.files, op.FD)
			return f.Close()
		}
		if _, err := f.WriteAt([]byte(op.Data), 0); err != nil {
			return err
		}
		return f.Sync()
	case "rename", "link":
		if op.Path == "" || op.To == "" {
			return syscall.EINVAL
		}
		if op.Op == "rename" {
			return os.Rename(path, destination)
		}
		return os.Link(path, destination)
	case "unlink":
		if op.Path == "" {
			return syscall.EINVAL
		}
		return syscall.Unlink(path)
	case "truncate":
		if op.Path == "" {
			return syscall.EINVAL
		}
		return os.Truncate(path, op.Size)
	case "chmod":
		if op.Path == "" {
			return syscall.EINVAL
		}
		return syscall.Chmod(path, op.Mode)
	default:
		return syscall.EINVAL
	}
}

func (s *server) snapshot() map[string]any {
	result := map[string]any{}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return map[string]any{"errno": errno(err)}
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, "path:"+entry.Name())
	}
	for name := range s.files {
		names = append(names, "fd:"+name)
	}
	sort.Strings(names)
	aliases := map[[2]uint64]string{}
	for _, name := range names {
		var info os.FileInfo
		var data []byte
		var statErr, readErr error
		if name[:3] == "fd:" {
			f := s.files[name[3:]]
			info, statErr = f.Stat()
			if statErr == nil {
				data = make([]byte, min(info.Size(), 8192))
				var count int
				count, readErr = f.ReadAt(data, 0)
				data = data[:count]
				if errors.Is(readErr, io.EOF) {
					readErr = nil
				}
			}
		} else {
			path := filepath.Join(s.root, name[5:])
			info, statErr = os.Lstat(path)
			if statErr == nil && info.Mode().IsRegular() {
				f, openErr := os.Open(path)
				readErr = openErr
				if openErr == nil {
					data, readErr = io.ReadAll(io.LimitReader(f, 8192))
					// Opening revalidates NFS close-to-open attributes. Describe
					// the same descriptor as the bytes, not the pre-open cached
					// pathname stat (which may still have the old truncate size).
					info, statErr = f.Stat()
					f.Close()
				}
			}
		}
		if statErr != nil {
			result[name] = map[string]any{"errno": errno(statErr)}
			continue
		}
		st := info.Sys().(*syscall.Stat_t)
		key := [2]uint64{uint64(st.Dev), uint64(st.Ino)}
		alias, exists := aliases[key]
		if !exists {
			alias = name
			aliases[key] = alias
		}
		hash := sha256.Sum256(data)
		// Keep raw nlink and namespace entries: NFS sillyrename may retain a
		// link for an open-unlinked file. That evidence must not be normalized
		// into POSIX nlink=0 or hide meaningful hard-link/namespace differences.
		result[name] = map[string]any{
			"type": uint32(st.Mode) & syscall.S_IFMT, "mode": uint32(st.Mode) & 07777,
			"uid": st.Uid, "gid": st.Gid, "size": info.Size(), "nlink": st.Nlink,
			"same_as": alias, "sha256": hex.EncodeToString(hash[:]), "read_errno": errno(readErr),
		}
	}
	return result
}

func serve(root, socket string) error {
	syscall.Umask(0)
	// New fixtures use a dedicated child of the fresh volume mount, so ext4's
	// root lost+found is not mistaken for workload data. Never filter entries:
	// replay fixtures retaining /data still observe the authoritative root.
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-signals; listener.Close() }()
	s := server{root: root, files: map[string]*os.File{}}
	defer func() {
		for _, f := range s.files {
			f.Close()
		}
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		var op operation
		err = json.NewDecoder(io.LimitReader(conn, 65536)).Decode(&op)
		if err != nil {
			json.NewEncoder(conn).Encode(map[string]any{"protocol_error": err.Error()})
			conn.Close()
			continue
		}
		err = s.apply(op)
		json.NewEncoder(conn).Encode(map[string]any{"errno": errno(err), "entries": s.snapshot()})
		conn.Close()
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("expected serve or request")
	}
	socket := "/probe.sock"
	switch os.Args[1] {
	case "serve":
		root := "/data"
		if len(os.Args) == 4 {
			root, socket = os.Args[2], os.Args[3]
		}
		// Only this container's private control socket, never volume contents.
		if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
			return err
		}
		return serve(root, socket)
	case "request":
		if len(os.Args) < 3 {
			return fmt.Errorf("missing request JSON")
		}
		if len(os.Args) == 4 {
			socket = os.Args[3]
		}
		var conn net.Conn
		var err error
		deadline := time.Now().Add(10 * time.Second)
		for {
			conn, err = net.DialTimeout("unix", socket, time.Second)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				return err
			}
			time.Sleep(20 * time.Millisecond)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err = fmt.Fprintln(conn, os.Args[2]); err != nil {
			return err
		}
		// Signal the request boundary even for truncated JSON, so the server
		// reports a protocol error instead of waiting for the I/O deadline.
		if err = conn.(*net.UnixConn).CloseWrite(); err != nil {
			return err
		}
		// The protocol contains one JSON reply, not an EOF-delimited stream.
		// Linux can report ECONNRESET after the reply when the peer closes;
		// waiting for EOF through splice turned complete replies into failures.
		var reply json.RawMessage
		if err := json.NewDecoder(io.LimitReader(conn, 1024*1024)).Decode(&reply); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(reply)
	default:
		return fmt.Errorf("unknown command")
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

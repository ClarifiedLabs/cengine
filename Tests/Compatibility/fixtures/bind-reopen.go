//go:build linux

// Stdlib-only, static reopen probe. Never stat the input: even fstat can repair
// the stale attributes this test measures. The caller supplies the mmap length.
package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"
)

const maxBytes = 1024 * 1024

func emit(data []byte) error {
	n, err := os.Stdout.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return err
}

func splice(fd int) error {
	pipe := make([]int, 2)
	if err := syscall.Pipe2(pipe, syscall.O_CLOEXEC); err != nil {
		return err
	}
	defer syscall.Close(pipe[0])
	defer syscall.Close(pipe[1])

	// Linux pipes hold at least one 4096-byte page. Start each splice with an
	// empty pipe, then drain exactly its returned count before producing again.
	// Splicing the entire file before draining would deadlock above pipe capacity.
	buffer := make([]byte, 4096)
	total := 0
	for {
		n, err := syscall.Splice(fd, nil, pipe[1], nil, len(buffer), 0)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		total += int(n)
		if total > maxBytes {
			return fmt.Errorf("splice output exceeds size bound")
		}
		for remaining := int(n); remaining > 0; {
			count, err := syscall.Read(pipe[0], buffer[:remaining])
			if err == syscall.EINTR {
				continue
			}
			if err != nil {
				return err
			}
			if count == 0 {
				return io.ErrUnexpectedEOF
			}
			if err := emit(buffer[:count]); err != nil {
				return err
			}
			remaining -= count
		}
	}
}

func mmap(fd, length int) error {
	if length > 0 {
		mapping, err := syscall.Mmap(fd, 0, length, syscall.PROT_READ, syscall.MAP_SHARED)
		if err != nil {
			return err
		}
		defer syscall.Munmap(mapping)
		// Fault every byte in userspace before any other operation on this fd.
		// SIGBUS (e.g. stale EOF after growth) is an authoritative test failure.
		data := append([]byte(nil), mapping...)
		if err := emit(data); err != nil {
			return err
		}
	}
	// A zero-length mmap is invalid. Check empty files with read(2), and for
	// nonempty mappings check EOF only AFTER consuming the mapping. Emit any
	// extra byte so stale trailing contents cannot produce a false exact match.
	if _, err := syscall.Seek(fd, int64(length), 0); err != nil {
		return err
	}
	var extra [1]byte
	for {
		n, err := syscall.Read(fd, extra[:])
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		return emit(extra[:n])
	}
}

func run() error {
	if len(os.Args) != 4 || (os.Args[1] != "splice" && os.Args[1] != "mmap") {
		return fmt.Errorf("usage: bind-reopen splice|mmap PATH EXPECTED_LENGTH")
	}
	length, err := strconv.Atoi(os.Args[3])
	if err != nil || length < 0 || length > maxBytes {
		return fmt.Errorf("expected length must be in [0, %d]", maxBytes)
	}
	// Raw open avoids convenience readers that stat/fstat before reading.
	fd, err := syscall.Open(os.Args[2], syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if os.Args[1] == "splice" {
		return splice(fd) // Deliberately read to actual EOF, not expected length.
	}
	return mmap(fd, length)
}

func main() {
	time.AfterFunc(20*time.Second, func() {
		fmt.Fprintln(os.Stderr, "bind-reopen deadline exceeded")
		os.Exit(124)
	})
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

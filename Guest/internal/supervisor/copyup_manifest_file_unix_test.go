//go:build darwin || linux

package supervisor

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	"golang.org/x/sys/unix"
)

func TestManagedManifestFileNeverRegistersWithRuntimePoller(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest")
	// Keep the existing >1 MiB compatibility boundary, not an ioctl-sized cap.
	content := bytes.Repeat([]byte("m"), (1<<20)+1)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file, err := managedManifestFile(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	// Use the original fd: File.Fd can itself change blocking mode.
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK != 0 {
		t.Fatalf("pollable descriptor: flags=%#x err=%v", flags, err)
	}
	if err := file.SetReadDeadline(time.Now()); !errors.Is(err, os.ErrNoDeadline) {
		t.Fatalf("runtime poll registration: %v", err)
	}
	got, err := io.ReadAll(io.LimitReader(file, a.MaxCopyManifestBytes+1))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatal("manifest bytes changed", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("descriptor retained after close", err)
	}
}

func TestManagedManifestFileRejectsNonRegularAndOversizedBeforeWrapping(t *testing.T) {
	for _, kind := range []string{"fifo", "directory", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest")
			var err error
			switch kind {
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "oversized":
				err = os.WriteFile(path, nil, 0600)
				if err == nil {
					err = os.Truncate(path, a.MaxCopyManifestBytes+1)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			file, err := managedManifestFile(fd)
			if err == nil || file != nil {
				if file != nil {
					file.Close()
				}
				t.Fatal("unsafe manifest accepted")
			}
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Fatal("rejected descriptor leaked", err)
			}
		})
	}
}

func TestManagedManifestFileExactSizeBoundaryAndNoFollow(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "manifest")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int64{0, a.MaxCopyManifestBytes} {
		if err := os.Truncate(path, size); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		file, err := managedManifestFile(fd)
		if err != nil {
			t.Fatal("existing size boundary rejected", size, err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(link, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		unix.Close(fd)
		t.Fatal("symlink followed")
	}
	fd, err = unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	file, err := managedManifestFile(fd)
	if err == nil || file != nil {
		t.Fatal("closed descriptor accepted", err)
	}
}

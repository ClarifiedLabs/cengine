//go:build linux && (arm64 || amd64)

package workloadstorage

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storageclient"
	"dev.cengine/guest/internal/storagefuse"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

const testAttachmentID = "11111111-1111-4111-8111-111111111111"

func attachmentTestBase(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("requires Linux root; composition preflight also requires a private /run mount")
	}
	// /tmp is deliberately inadmissible to storagefuse's trusted-ancestor walk.
	// Use only our exclusive sandbox, never the live /run/cengine hierarchy.
	base, err := os.MkdirTemp("/run", "cengine-attachment-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	return base
}

func attachmentPreflightConfig(t *testing.T, path string) storagefuse.Config {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = local.Close(); _ = remote.Close() })
	limits := c.DefaultLimits()
	limits.Requests = 0 // mountOptions returns ErrCapacity only AFTER real preflight.
	return storagefuse.Config{
		Client: c.Config{
			// Preflight must not use or consume transport; no TLS handshake, DATA
			// exchange, /dev/fuse access or mount syscall is reached by this test.
			Conn:          tls.Client(local, &tls.Config{MinVersion: tls.VersionTLS13}),
			Authority:     a.DataHello{Binding: a.Binding{Mode: a.ReadWrite, Role: a.RuntimeRole}},
			Version:       w.Version,
			Profile:       w.RequiredProfile(),
			SupportedCaps: (uint64(1) << (unix.CAP_LAST_CAP + 1)) - 1,
			Limits:        limits,
			Timeout:       time.Second,
		},
		Mountpoint: path,
		Retire:     func(error) { t.Error("preflight consumed attachment ownership") },
	}
}

func TestAttachmentDirectoryComposesWithStoragefusePreflight(t *testing.T) {
	base := attachmentTestBase(t)
	path, err := makeAttachmentDirectoryIn(base, testAttachmentID)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, "managed", testAttachmentID, "root"); path != want {
		t.Fatalf("mountpoint = %q, want %q", path, want)
	}
	for _, parent := range []string{filepath.Join(base, "managed"), filepath.Dir(path)} {
		stat, err := os.Lstat(parent)
		if err != nil || !stat.IsDir() || stat.Mode().Perm() != 0700 {
			t.Fatalf("private parent %q: %v, %v", parent, stat, err)
		}
	}
	cfg := attachmentPreflightConfig(t, path)
	for i := 0; i < 2; i++ { // failed preflight must also release its path claim.
		mounted, err := storagefuse.Mount(cfg)
		if mounted != nil || !errors.Is(err, c.ErrCapacity) {
			t.Fatalf("setup did not pass real storagefuse preflight: mounted=%v err=%v", mounted, err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("final leaf must remain absent before storagefuse owns creation: %v", err)
		}
	}
}

func TestAttachmentPreflightRejectsExistingLeafWithoutCleanup(t *testing.T) {
	for _, kind := range []string{"directory", "file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			base := attachmentTestBase(t)
			path, err := makeAttachmentDirectoryIn(base, testAttachmentID)
			if err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(base, "sentinel")
			if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "directory":
				err = os.Mkdir(path, 0700)
			case "file":
				err = os.WriteFile(path, []byte("keep"), 0600)
			case "symlink":
				err = os.Symlink(sentinel, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			mounted, err := storagefuse.Mount(attachmentPreflightConfig(t, path))
			if mounted != nil || !errors.Is(err, storagefuse.ErrProfile) {
				t.Fatalf("existing leaf accepted: mounted=%v err=%v", mounted, err)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("preflight changed an unowned leaf: %v", err)
			}
			if data, err := os.ReadFile(sentinel); err != nil || string(data) != "keep" {
				t.Fatalf("symlink target changed: %q, %v", data, err)
			}
		})
	}
}

func TestAttachmentDirectoryRejectsSymlinksAndExistingAttachment(t *testing.T) {
	for _, component := range []string{"base", "managed", "attachment", "existing-attachment", "writable-managed"} {
		t.Run(component, func(t *testing.T) {
			base := attachmentTestBase(t)
			target := filepath.Join(base, "target")
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			managed := filepath.Join(base, "managed")
			setupBase := base
			var err error
			switch component {
			case "base":
				setupBase = filepath.Join(base, "link")
				err = os.Symlink(target, setupBase)
			case "managed":
				err = os.Symlink(target, managed)
			case "attachment", "existing-attachment":
				if err := os.Mkdir(managed, 0700); err != nil {
					t.Fatal(err)
				}
				attachment := filepath.Join(managed, testAttachmentID)
				if component == "attachment" {
					err = os.Symlink(target, attachment)
				} else {
					err = os.Mkdir(attachment, 0700)
				}
			case "writable-managed":
				if err := os.Mkdir(managed, 0700); err != nil {
					t.Fatal(err)
				}
				err = os.Chmod(managed, 0777)
			}
			if err != nil {
				t.Fatal(err)
			}
			if path, err := makeAttachmentDirectoryIn(setupBase, testAttachmentID); err == nil || path != "" {
				t.Fatalf("unsafe component accepted: path=%q err=%v", path, err)
			}
			if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
				t.Fatalf("followed a symlink: %v, %v", entries, err)
			}
		})
	}
}

func TestAttachmentDirectoryRejectsInvalidIDBeforeOpeningBase(t *testing.T) {
	for _, attachment := range []string{"", "..", "../" + testAttachmentID, testAttachmentID + "/root"} {
		if path, err := makeAttachmentDirectoryIn("/must/not/be/opened", attachment); path != "" || !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("invalid ID %q: path=%q err=%v", attachment, path, err)
		}
	}
}
